import {
  useEffect,
  useMemo,
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
  Input,
} from "../../components/ui/Input";

import {
  Table,
} from "../../components/ui/Table";

import {
  getMachineDetail,
} from "../../lib/api";

import type {
  MachineDetail,
} from "../../types/machine";


function formatInventoryDate(
  value: string | null,
): string {
  if (!value) {
    return "Jamais";
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
  value:
    | string
    | null,
): string {
  return value?.trim()
    || "Non renseigné";
}


export function MachineDetailPage() {
  const {
    machineId,
  } = useParams();

  const [
    machine,
    setMachine,
  ] = useState<
    MachineDetail | null
  >(null);

  const [
    componentSearch,
    setComponentSearch,
  ] = useState("");

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

    async function loadMachine() {
      if (!machineId) {
        setError(
          "Identifiant machine invalide.",
        );

        setIsLoading(false);

        return;
      }

      setIsLoading(true);
      setError(null);

      try {
        const result =
          await getMachineDetail(
            machineId,
          );

        if (!cancelled) {
          setMachine(
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

    void loadMachine();

    return () => {
      cancelled = true;
    };
  }, [
    machineId,
  ]);


  const filteredComponents =
    useMemo(() => {
      if (!machine) {
        return [];
      }

      const value =
        componentSearch
          .trim()
          .toLowerCase();

      if (!value) {
        return machine.components;
      }

      return machine.components.filter(
        (component) => {
          const searchable = [
            component.name,
            component.version,
            component.vendor,
            component.component_type,
            component.ecosystem,
          ]
            .filter(Boolean)
            .join(" ")
            .toLowerCase();

          return searchable.includes(
            value,
          );
        },
      );
    }, [
      machine,
      componentSearch,
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
              Chargement de la machine...
            </span>
          </div>
        </Card>
      </main>
    );
  }


  if (
    error
    || !machine
  ) {
    return (
      <main className="security-page">
        <Link
          to="/machines"
          className="back-link"
        >
          ← Retour aux machines
        </Link>

        <Card>
          <div className="error-state">
            <strong>
              Machine indisponible
            </strong>

            <span>
              {
                error
                ?? "Machine introuvable."
              }
            </span>
          </div>
        </Card>
      </main>
    );
  }


  return (
    <main className="security-page">
      <Link
        to="/machines"
        className="back-link"
      >
        ← Retour aux machines
      </Link>

      <header className="machine-detail-header">
        <div>
          <span className="eyebrow">
            Fiche machine
          </span>

          <h1>
            {machine.hostname}
          </h1>

          <p>
            Inventaire logiciel et
            expositions associées à cette
            machine.
          </p>
        </div>

        <span className="machine-detail-id">
          {machine.machine_id}
        </span>
      </header>

      <section className="machine-info-grid">
        <Card>
          <span className="info-label">
            Système
          </span>

          <strong className="info-value">
            {machine.os_name}
          </strong>

          <span className="info-detail">
            {machine.os_version}
          </span>
        </Card>

        <Card>
          <span className="info-label">
            Architecture
          </span>

          <strong className="info-value">
            {machine.architecture}
          </strong>
        </Card>

        <Card>
          <span className="info-label">
            Dernier inventaire
          </span>

          <strong className="info-value info-value--small">
            {formatInventoryDate(
              machine.last_inventory_at,
            )}
          </strong>
        </Card>

        <Card>
          <span className="info-label">
            Composants
          </span>

          <strong className="info-value">
            {machine.components.length}
          </strong>
        </Card>

        <Card>
          <span className="info-label">
            Expositions
          </span>

          <strong className="info-value">
            {machine.exposures.length}
          </strong>
        </Card>

        <Card>
          <span className="info-label">
            Machine UID
          </span>

          <strong className="info-value info-value--uuid">
            {machine.machine_uid}
          </strong>
        </Card>
      </section>

      <section className="machine-detail-section">
        <div className="machine-section-header">
          <div>
            <h2>
              Inventaire logiciel
            </h2>

            <p>
              Composants détectés lors du
              dernier inventaire.
            </p>
          </div>

          <div className="machine-component-search">
            <Input
              type="search"
              placeholder="Rechercher un logiciel..."
              value={componentSearch}
              onChange={(event) => {
                setComponentSearch(
                  event.target.value,
                );
              }}
            />
          </div>
        </div>

        {filteredComponents.length === 0 ? (
          <Card>
            <div className="dashboard-empty">
              <strong>
                Aucun composant
              </strong>

              <span>
                Aucun logiciel ne correspond
                à cette recherche.
              </span>
            </div>
          </Card>
        ) : (
          <Table>
            <thead>
              <tr>
                <th>
                  Type
                </th>

                <th>
                  Logiciel
                </th>

                <th>
                  Version
                </th>

                <th>
                  Vendor / Écosystème
                </th>

                <th>
                  Détection
                </th>
              </tr>
            </thead>

            <tbody>
              {filteredComponents.map(
                (component) => (
                  <tr
                    key={
                      component.component_id
                    }
                  >
                    <td>
                      <span
                        className={
                          `component-type component-type--${component.component_type}`
                        }
                      >
                        {
                          component.component_type
                        }
                      </span>
                    </td>

                    <td>
                      <strong className="component-name">
                        {component.name}
                      </strong>
                    </td>

                    <td>
                      {displayValue(
                        component.version,
                      )}
                    </td>

                    <td>
                      {displayValue(
                        component.vendor
                        ?? component.ecosystem,
                      )}
                    </td>

                    <td>
                      <span className="detector-value">
                        {
                          component.detected_by
                        }
                      </span>
                    </td>
                  </tr>
                ),
              )}
            </tbody>
          </Table>
        )}
      </section>

      <section className="machine-detail-section">
        <div className="machine-section-header">
          <div>
            <h2>
              Expositions associées
            </h2>

            <p>
              Vulnérabilités corrélées aux
              composants de cette machine.
            </p>
          </div>
        </div>

        {machine.exposures.length === 0 ? (
          <Card>
            <div className="machine-exposure-empty">
              <strong>
                Aucune exposition détectée
              </strong>

              <span>
                Aucune vulnérabilité n'est
                actuellement associée aux
                composants de cette machine.
              </span>
            </div>
          </Card>
        ) : (
          <Table>
            <thead>
              <tr>
                <th>
                  Vulnérabilité
                </th>

                <th>
                  Composant
                </th>

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
                  Matching
                </th>
              </tr>
            </thead>

            <tbody>
              {machine.exposures.map(
                (exposure) => (
                  <tr
                    key={
                      exposure.exposure_id
                    }
                  >
                    <td>
                      <strong>
                        {
                          exposure
                            .primary_identifier
                          ?? (
                            exposure
                              .canonical_vulnerability_id
                              .slice(
                                0,
                                8,
                              )
                          )
                        }
                      </strong>
                    </td>

                    <td>
                      <strong>
                        {
                          exposure
                            .component_name
                        }
                      </strong>

                      <div className="table-secondary">
                        {
                          exposure
                            .component_version
                          ?? "Version inconnue"
                        }
                      </div>
                    </td>

                    <td>
                      <span
                        className={
                          (
                            "applicability-badge "
                            + `applicability-badge--${exposure.applicability_status}`
                          )
                        }
                      >
                        {
                          exposure
                            .applicability_status
                        }
                      </span>
                    </td>

                    <td>
                      {
                        exposure.severity
                        ?? "—"
                      }
                    </td>

                    <td>
                      {
                        exposure.priority
                        ?? "—"
                      }
                    </td>

                    <td>
                      {
                        exposure.is_kev
                        ? "Oui"
                        : "Non"
                      }
                    </td>

                    <td>
                      <span className="detector-value">
                        {
                          exposure.match_rule
                        }
                      </span>

                      {exposure.match_version && (
                        <div className="table-secondary">
                          {
                            exposure
                              .match_version
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
      </section>
    </main>
  );
}